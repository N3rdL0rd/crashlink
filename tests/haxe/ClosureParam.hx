class ClosureParam {
    static function main() {
        var base = 10;
        var add = () -> base;
        base = 20;
        Sys.println(add());
    }
}
