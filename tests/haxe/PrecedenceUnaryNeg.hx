class PrecedenceUnaryNeg {
    static function negSum(a: Int, b: Int): Int {
        // -(a + b), NOT -a + b
        return -(a + b);
    }

    static function negProdSum(a: Int, b: Int, c: Int): Int {
        // -(a * b) + c, NOT -a * (b + c) or similar mis-grouping
        return -(a * b) + c;
    }

    static function subNeg(a: Int, b: Int): Int {
        // a - (-(b))  simplifies but test explicit negation nested in sub chain
        return a - (-b + 1);
    }

    public static function main(): Void {
        trace(negSum(3, 5));
        trace(negProdSum(3, 5, 2));
        trace(subNeg(10, 4));
    }
}
