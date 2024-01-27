// Annotated Basic Rust Example: Factorial Calculation 

// Define a function to calculate the factorial of a number.
fn factorial(n: u64) -> u64 {
    // Base case: If n is 0 or 1, the factorial is 1.
    if n == 0 || n == 1 {
        1
    } else {
        // Recursive case: Calculate factorial by calling the function recursively.
        n * factorial(n - 1)
    }
} 

fn main() {
    // Define the number for which we want to calculate the factorial.
    let num: u64 = 6; 

    // Call the factorial function and store the result.
    let result = factorial(num); 

    // Print the result to the console.
    println!("Factorial of {} is: {}", num, result);
}