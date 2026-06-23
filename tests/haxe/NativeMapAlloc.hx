class NativeMapAlloc {
    static function main() {
        var b = new hl.types.BytesMap();
        var i = new hl.types.IntMap();
        var o = new hl.types.ObjectMap();
        trace(b);
        trace(i);
        trace(o);
    }
}
