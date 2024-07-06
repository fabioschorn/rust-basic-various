use std::io::{BufRead, Write};
use std::path::Path;

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:9999").unwrap();
    for mut stream in listener.incoming().flatten() {
        let mut rdr = std::io::BufReader::new(&mut stream);
        let mut l = String::new();
        rdr.read_line(&mut l).unwrap();
        match l.trim().split(' ').collect::<Vec<_>>().as_slice() {
            ["GET", resource, "HTTP/1.1"] => {
                loop {
                    let mut l = String::new();
                    rdr.read_line(&mut l).unwrap();
                    if l.trim().is_empty() { break; }
                }
                let mut p = std::path::PathBuf::new();
                p.push("htdocs");
                p.push(resource.trim_start_matches('/'));
                if resource.ends_with('/') { p.push("index.html"); }
                println!("Accessing path: {:?}", p); // Debug statement
                
                if !p.exists() {
                    println!("Path does not exist: {:?}", p);
                } else if !p.is_file() {
                    println!("Path is not a file: {:?}", p);
                } else {
                    println!("Path is valid, proceeding to read the file.");
                }

                match std::fs::read(&p) {
                    Ok(content) => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                        stream.write_all(&content).unwrap();
                    }
                    Err(e) => {
                        eprintln!("Failed to read file: {:?}", e);
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap();
                    }
                }
            }
            _ => todo!()
        }
    }
}