class SharedClosureAlias {
    static function main() {
        var counter = 0;
        var inc = function() { counter += 1; };
        var get = function() { return counter; };
        inc();
        inc();
        inc();
        trace(get());
    }
}
