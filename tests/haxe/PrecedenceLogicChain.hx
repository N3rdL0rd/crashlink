class PrecedenceLogicChain {
    static function orAnd(a: Bool, b: Bool, c: Bool): Bool {
        // a || (b && c), NOT (a || b) && c
        return a || (b && c);
    }

    static function andOr(a: Bool, b: Bool, c: Bool): Bool {
        return (a && b) || c;
    }

    static function eqChain(a: Int, b: Int, c: Bool): Bool {
        // (a == b) == c, equality is left-assoc but mixing types matters
        return (a == b) == c;
    }

    static function notOr(a: Bool, b: Bool): Bool {
        // !(a || b), NOT (!a) || b
        return !(a || b);
    }

    public static function main(): Void {
        trace(orAnd(true, false, false));
        trace(orAnd(false, true, true));
        trace(andOr(true, false, true));
        trace(eqChain(1, 1, true));
        trace(notOr(false, false));
        trace(notOr(true, false));
    }
}
