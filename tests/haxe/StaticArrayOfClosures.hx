class StaticArrayOfClosures {
    static var ops:Array<Int->Int> = [
        function(x) return x + 1,
        function(x) return x * 2,
        function(x) return x - 3
    ];

    static function main() {
        var r = 10;
        for (op in ops) {
            r = op(r);
            trace(r);
        }
        trace(ops[1](5));
    }
}
