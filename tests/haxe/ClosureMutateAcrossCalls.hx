class ClosureMutateAcrossCalls {
    static function makeAccum():Void -> Int {
        var total = 0;
        return function():Int {
            total += 10;
            return total;
        };
    }

    static function main() {
        var acc = makeAccum();
        Sys.println(acc());
        Sys.println(acc());
        Sys.println(acc());

        var x = 1;
        var addAndDouble:Void -> Int = function():Int {
            x = x * 2;
            return x;
        };
        Sys.println(addAndDouble());
        Sys.println(addAndDouble());
        x = 100;
        Sys.println(addAndDouble());
    }
}
