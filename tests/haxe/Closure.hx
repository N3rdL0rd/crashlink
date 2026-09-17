class Closure {
    static function main() {
        var fun = () -> "hello";
        trace(fun());
        trace(fun);
        (() -> { trace(" there"); })();
    }
}