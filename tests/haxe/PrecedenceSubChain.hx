class PrecedenceSubChain {
    static function subAdd(a: Int, b: Int, c: Int): Int {
        // a - (b + c), NOT a - b + c
        return a - (b + c);
    }

    static function subSub(a: Int, b: Int, c: Int): Int {
        // a - (b - c) = a - b + c, NOT a - b - c
        return a - (b - c);
    }

    static function divMul(a: Int, b: Int, c: Int): Int {
        // a / (b * c), NOT a / b * c
        return Std.int(a * 1000000 / (b * c));
    }

    static function modChain(a: Int, b: Int, c: Int): Int {
        // a - (b % c), NOT a - b % c (both same precedence L-to-R actually, but test anyway)
        return a - (b % c);
    }

    public static function main(): Void {
        var r1 = subAdd(10, 3, 2);
        var r2 = subSub(10, 3, 2);
        var r3 = divMul(120, 4, 3);
        var r4 = modChain(10, 7, 4);
        trace(r1);
        trace(r2);
        trace(r3);
        trace(r4);
    }
}
