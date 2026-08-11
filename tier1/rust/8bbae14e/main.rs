mod work;

fn main() {
    let value = std::env::args().nth(1).unwrap_or_default();
    println!("{}", work::handle(&value));
}
