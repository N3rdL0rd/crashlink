class LoopBranchTempReuse {
    static function main() {
        var acc = 0;
        for (i in 0...6) {
            var t:Int;
            if (i % 2 == 0) {
                t = i * 10;
            } else {
                t = i * 100 + 1;
            }
            acc += t;
            Sys.println('i=$i t=$t acc=$acc');
        }
        Sys.println("final=" + acc);
    }
}
