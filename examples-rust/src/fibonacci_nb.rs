// Annotated Advanced Rust Example: Fibonacci Sequence

// Declare a function to calculate the nth Fibonacci number using dynamic programming.
fn fibonacci_dynamic(n: u64) -> u64 {
    // Create a vector to store the Fibonacci numbers.
    let mut fib_nums: Vec<u64> = Vec::with_capacity(n as usize + 1);

    // Initialize the first two Fibonacci numbers.
    fib_nums.push(0);
    fib_nums.push(1);

    // Calculate and store Fibonacci numbers from the 3rd to the nth.
    for i in 2..=n {
        let next_fib = fib_nums[i as usize - 1] + fib_nums[i as usize - 2];
        fib_nums.push(next_fib);
    }

    // Return the nth Fibonacci number.
    fib_nums[n as usize]
}

fn main() {
    // Define the value of n for which we want to calculate the Fibonacci number.
    let n: u64 = 10;

    // Call the fibonacci_dynamic function and store the result.
    let result = fibonacci_dynamic(n);

    // Print the result.
    println!("The {}th Fibonacci number is: {}", n, result);
}
