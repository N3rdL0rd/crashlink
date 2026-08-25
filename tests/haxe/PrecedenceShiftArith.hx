class PrecedenceShiftArith {
    static function shiftOfSum(a: Int, b: Int): Int {
        // (a + b) << 2, NOT a + (b << 2) -- shift has LOWER precedence than + in Haxe
        return (a + b) << 2;
    }

    static function sumOfShift(a: Int, b: Int): Int {
        return a + (b << 2);
    }

    static function shiftAndMask(a: Int, b: Int): Int {
        // (a << 2) & b, shift binds tighter than &
        return (a << 2) & b;
    }

    static function orOfShiftSum(a: Int, b: Int, c: Int): Int {
        // ((a + b) << 1) | c
        return ((a + b) << 1) | c;
    }

    public static function main(): Void {
        trace(shiftOfSum(3, 5));
        trace(sumOfShift(3, 5));
        trace(shiftAndMask(3, 0xF));
        trace(orOfShiftSum(3, 5, 1));
    }
}
