class LoopVarReassign {
    static function main() {
        var sum = 0;
        for (i in 0...5) {
            var i2 = i * 10;
            sum += i2;
        }
        Sys.println(sum);

        var arr = [1, 2, 3];
        var total = 0;
        for (i in 0...arr.length) {
            var i = arr[i] * 2;
            total += i;
        }
        Sys.println(total);
    }
}
