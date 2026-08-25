class PrecedenceTernaryMix {
    static function addTernary(a: Int, cond: Bool, b: Int, c: Int): Int {
        // a + (cond ? b : c)
        return a + (cond ? b : c);
    }

    static function mulTernary(a: Int, cond: Bool, b: Int, c: Int): Int {
        return a * (cond ? b : c) + 1;
    }

    static function negTernary(cond: Bool, b: Int, c: Int): Int {
        // -(cond ? b : c), NOT (cond ? -b : c) etc
        return -(cond ? b : c);
    }

    public static function main(): Void {
        trace(addTernary(10, true, 2, 5));
        trace(addTernary(10, false, 2, 5));
        trace(mulTernary(3, true, 4, 9));
        trace(mulTernary(3, false, 4, 9));
        trace(negTernary(true, 7, 2));
        trace(negTernary(false, 7, 2));
    }
}
