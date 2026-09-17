class DoWhileBreakCase {
    public static function firstMultipleOfThree(limit: Int): Int {
        var b = 0;
        do {
            b = b + 1;
            if (b % 3 == 0) {
                break;
            }
        } while (b < limit);
        return b;
    }

    public static function main(): Void {
        var b = firstMultipleOfThree(10);
    }
}
