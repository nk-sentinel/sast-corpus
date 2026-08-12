public final class Cli {
    public static void main(String[] args) {
        System.out.println(Handler.handle(args.length > 0 ? args[0] : ""));
    }
}
