class SimpleIf {
    public static function call() {}
    
    static function main() {
        var a = 500;
        if (a > 400) {
            call();
            call();
            call();
        } else {
            call();
        }
        a = 300;
        var b = 999;
    }
}
