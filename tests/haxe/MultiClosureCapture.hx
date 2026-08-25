class MultiClosureCapture {
    static function main() {
        var fns = new Array<Void->Int>();
        for (i in 0...3) {
            var a = i * 10;
            var b = i * 100;
            fns.push(function() { return a + b; });
        }
        for (f in fns) {
            Sys.println(f());
        }

        var x = 1;
        var y = 2;
        var f1 = function() { return x + y; };
        var f2 = function() { x = x + 5; return x; };
        Sys.println(f1());
        Sys.println(f2());
        Sys.println(f1());
    }
}
