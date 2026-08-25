class LoopClosureCapture {
    static function main() {
        var fns = [];
        for (i in 0...3) {
            fns.push(function() return i);
        }
        var sum = 0;
        for (f in fns) sum += f();
        Sys.println(sum);
    }
}
