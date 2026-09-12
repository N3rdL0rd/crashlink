class DoWhileBreakCase {
    // Regression for a do-while whose internal `break` fires before the trailing
    // `while` condition is ever checked: HL's CFG can route the jump's "true"
    // edge back into the loop body instead of out to the exit, so a lifter that
    // always assumes "true means exit" recovers an inverted break condition.
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
