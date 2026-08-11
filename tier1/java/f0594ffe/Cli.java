package app;

public class Cli {
    public static void main(String[] args) {
        System.out.println(Gate.handle(args[0], args[1]));
    }
}
