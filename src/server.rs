use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;

pub fn start_listening_and_wait_for_oauth_response() -> Option<[u8; 512]>{
    let listener = TcpListener::bind("127.0.0.1:3000").unwrap();

    for stream in listener.incoming() {
        let (is_oauth_response, response) = handle_connection(stream.unwrap());

        if is_oauth_response {
            return response;
        } else {
            continue;
        }
    }

    // We should never get here since we will just keep waiting for tokens until we get them
    None
}

fn handle_connection(mut stream: TcpStream) -> (bool, Option<[u8; 512]>) {
    let mut buffer = [0; 512];
    let _ = stream.read(&mut buffer).unwrap();

    let get_oauth_response = b"GET /oauth_response";

    if buffer.starts_with(get_oauth_response) {
        respond_success(stream);
        (true, Some(buffer))
    } else {
        respond_failure(stream);
        (false, None)
    }
}

fn respond_success(mut stream: TcpStream) {
    let contents = "<html>\
        <head>\
            <title>Tweet Stream Success</title>\
        </head>\
        <body>\
            <h1>Success</h1>\
            <p>Access token has been recorded. You may return to your shell</p>\
        </body>\
    </html>";

    let response = format!("HTTP/1.1 200 OK\r\nContent-Length:{}\r\n\r\n{}", contents.as_bytes().len(), contents);

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn respond_failure(mut stream: TcpStream) {
    let contents = "<html>\
            <head>\
                <title>Not Found</title>\
            </head>\
            <body>\
                <h1>Error</h1>\
                <p>The requested URL was not found</p>\
            </body>\
        </html>";

    let response = format!("HTTP/1.1 404 NOT FOUND\r\nContent-Length:{}\r\n\r\n{}", contents.as_bytes().len(), contents);

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}