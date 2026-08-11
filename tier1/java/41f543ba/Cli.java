package app;

public class Cli {
    public static void main(String[] args) throws Exception {
        System.out.println(Runner.handle(args[0]));
    }
}
