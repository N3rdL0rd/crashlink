class PrecedenceShiftArith {
    static function shiftOfSum(a: Int, b: Int): Int {
        return (a + b) << 2;
    }

    static function sumOfShift(a: Int, b: Int): Int {
        return a + (b << 2);
    }

    static function shiftAndMask(a: Int, b: Int): Int {
        return (a << 2) & b;
    }

    static function orOfShiftSum(a: Int, b: Int, c: Int): Int {
        return ((a + b) << 1) | c;
    }

    public static function main(): Void {
        trace(shiftOfSum(3, 5));
        trace(sumOfShift(3, 5));
        trace(shiftAndMask(3, 0xF));
        trace(orOfShiftSum(3, 5, 1));
    }
}
