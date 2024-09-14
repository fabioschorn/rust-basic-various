use regex::Regex; // Importing the Regex struct from the regex crate
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    let file_path = "input.txt";

    // Open the input file and handle potential errors
    let file = match File::open(file_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Error opening the file: {}", error);
            return;
        }
    };

    // Create a BufReader to efficiently read the file line by line
    let reader = BufReader::new(file);

    // Define a regular expression to match potential passwords or API keys
    let password_regex = Regex::new(r"(?i)(password|api[_\s]?key)[:=]\s*(\w+)").unwrap();

    // Perform the security check by scanning each line of the file
    for (line_number, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("Error reading line {}: {}", line_number + 1, error);
                continue;
            }
        };

        // Search for matches in the current line using the password_regex
        if password_regex.is_match(&line) {
            println!(
                "Potential security issue found in line {}: {}",
                line_number + 1,
                line
            );
        }
    }
}
