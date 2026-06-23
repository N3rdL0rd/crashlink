class SetrefCase {
    static function main() {
        var x = 0;
        var r = new hl.Ref(x);
        r.set(42);
        trace(r.get());
    }
}
