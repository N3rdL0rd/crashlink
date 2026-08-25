class NullCoalesceOps {
    static var callCount = 0;

    static function sideEffect(v: Int): Null<Int> {
        callCount += 1;
        return v;
    }

    static function main() {
        var a: Null<Int> = null;
        var b = a ?? 42;
        trace(b);

        var c: Null<Int> = 7;
        var d = c ?? sideEffect(99);
        trace(d);
        trace(callCount);

        var e: Null<Int> = null;
        var f = e ?? sideEffect(5);
        trace(f);
        trace(callCount);

        var s: String = null;
        trace(s?.length);
    }
}
