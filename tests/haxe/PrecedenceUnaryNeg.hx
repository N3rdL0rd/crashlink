class PrecedenceUnaryNeg {
    static function negSum(a: Int, b: Int): Int {
        return -(a + b);
    }

    static function negProdSum(a: Int, b: Int, c: Int): Int {
        return -(a * b) + c;
    }

    static function subNeg(a: Int, b: Int): Int {
        return a - (-b + 1);
    }

    public static function main(): Void {
        trace(negSum(3, 5));
        trace(negProdSum(3, 5, 2));
        trace(subNeg(10, 4));
    }
}
