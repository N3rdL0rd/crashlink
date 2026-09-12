class ForLoopRegisterReuseCase {
    public static function sumRange(bound: Int): Int {
        var acc = 0;
        for (i in 0...bound) {
            acc += i;
        }
        var i = 1;
        acc += i;
        return acc;
    }

    public static function main(): Void {
        var r = sumRange(5);
    }
}
