class RecursiveClosureSelf {
    static function main() {
        var fact:Int -> Int = null;
        fact = function(n:Int):Int {
            if (n <= 1) return 1;
            return n * fact(n - 1);
        };
        Sys.println(fact(5));
        Sys.println(fact(6));

        var counter = 0;
        var tick:Int -> Void = null;
        tick = function(depth:Int):Void {
            counter++;
            if (depth > 0) tick(depth - 1);
        };
        tick(4);
        Sys.println(counter);
    }
}
