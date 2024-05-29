// Runs a simple Prover which connects to the Notary and notarizes a request/response from
// example.com. The Prover then generates a proof and writes it to disk.
#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]

use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tlsn_examples::{run_notary, request_notarization};
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig, ProverError};
use tracing::debug;
use futures_util::{StreamExt, SinkExt, stream::{SplitSink, SplitStream}};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream, tungstenite::protocol::Role, client_async};
use tokio::sync::mpsc;
use tokio::io::{self, AsyncBufReadExt};


const SERVER_DOMAIN: &str = "wbs.mexc.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 163840;

use std::str;

#[tokio::main]
async fn main() {

    tracing_subscriber::fmt::init();
    let (notary_tls_socket, session_id) =
    request_notarization(NOTARY_HOST, NOTARY_PORT, Some(NOTARY_MAX_TRANSCRIPT_SIZE)).await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Passing TLS Connection to Websocket Stream
    //let (ws_stream, _) = connect_async("wss://wbs.mexc.com/ws").await.expect("Failed to connect");
    let (mut ws_stream, _) = client_async("wss://wbs.mexc.com/ws", tls_connection.compat()).await.expect("Failed");
   
    //let mut ws_stream = WebSocketStream::from_raw_socket(tls_connection.compat(), Role::Client, None);
    //let (mut ws_stream, _) = client_async("wss://wbs.mexc.com/ws", ws_stream_ws.compat()).await.expect("Failed");
    //let mut completed_stream = ws_stream.await;
    println!("WebSocket handshake has been successfully completed");

    // let (mut write, mut read) = ws_stream.split();

    let subscribe = Message::Text(
        format!(
                r#"{{
                    "method":"SUBSCRIPTION", 
                    "params":["spot@public.deals.v3.api@BTCUSDT"] 
                }}"#,
            )
    );

    ws_stream.send(subscribe).await.expect("Failed to Suscrible");
    //completed_stream.send(subscribe).await.expect("Failed to Suscrible");
    println!("Sent data to stream.");

    //let read_handle = tokio::spawn(handle_incoming_messages(ws_stream));

    // tokio::spawn(async move {
    //     while let Some(message) = ws_stream.next().await {
    //         match message {
    //             Ok(msg) => {
    //                 // Process the received message (e.g., parse JSON, update UI)
    //                 println!("Received message: {:?}", msg);
    //             }
    //             Err(err) => println!("Error receiving message: {:?}", err),
    //         }
    //     }
    // });

    let mut message = ws_stream.next().await;
    //let mut message = completed_stream.next().await;
    match message {
        Some(Ok(msg)) => {
                // Process the received message (e.g., parse JSON, update UI)
                println!("Received message: {:?}", msg);
        }
        Some(Err(err)) => println!("Error receiving message: {:?}", err),
        Npne => {}
    }
                
    message = ws_stream.next().await;
    //let mut message = completed_stream.next().await;
    match message {
        Some(Ok(msg)) => {
                // Process the received message (e.g., parse JSON, update UI)
                println!("Received message: {:?}", msg);
        }
        Some(Err(err)) => println!("Error receiving message: {:?}", err),
        Npne => {}
    }

    let _ = ws_stream.close(None).await;
    //let _ = completed_stream.close(None).await;
    println!("Got a response from the server");

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();



    let proof = build_proof_without_redactions(prover).await;

    // Write the proof to a file
    let mut file = tokio::fs::File::create("websocket_proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to `websocket_proof_mexc.json`");
}

fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

async fn build_proof_without_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    let sent_len = prover.sent_transcript().data().len(); //Returns the transcript of the sent requests
    let recv_len = prover.recv_transcript().data().len(); //Returns the transcript of the received responses

    let builder = prover.commitment_builder(); // Builds the TranscriptCommitnment and returns a TranscriptCommitnmentBuilder object
   
    // Commits to the provided ranges of the sent transcript.
    let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();  
    // // Commits to the provided ranges of the received transcript
    let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    proof_builder.reveal_by_id(sent_commitment).unwrap();
    proof_builder.reveal_by_id(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap(); // tlsn_core::proof::SubstringsProof

    TlsProof {
        session: notarized_session.session_proof(), //tlsn_core::proof::SessionProof datatype
        substrings: substrings_proof, //
    }
}

async fn handle_incoming_messages(mut read: WebSocketStream<impl AsyncRead + AsyncWrite + Unpin>) {
    while let Some(message) = read.next().await {
        match message {
            Ok(msg) => {println!("Received a message: {}", msg);},
            Err(e) => eprintln!("Error receiving message: {}", e),
        }
    }
}

 //Build a simple HTTP request with common headers - for websocket
    // let request = Request::builder()
    //     .uri("/ws")
    //     .header("Host", SERVER_DOMAIN)
    //     .header("Upgrade", "websocket")
    //     // Using "identity" instructs the Server not to use compression for its HTTP response.
    //     // TLSNotary tooling does not support compression.
    //     .header("Connection", "Upgrade")
    //     .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
    //     .header("Sec-WebSocket-Version","13")
    //     .body(login_message)
    //     .unwrap();