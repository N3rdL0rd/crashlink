class ArrayReverseFloatCase {
    static function swapF64(bytes: hl.Bytes, i: Int, k: Int): Void {
        var tmp = bytes.getF64(i << 3);
        bytes.setF64(i << 3, bytes.getF64(k << 3));
        bytes.setF64(k << 3, tmp);
    }
    static function main() {
        var b = new hl.Bytes(16);
        b.setF64(0, 1.0);
        b.setF64(8, 2.0);
        swapF64(b, 0, 1);
        trace(b.getF64(0));
        trace(b.getF64(8));
    }
}
