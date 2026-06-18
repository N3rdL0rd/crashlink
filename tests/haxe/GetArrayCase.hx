// Targets GetArray: hl.NativeArray indexing lowers to the generic GetArray
// opcode for element reads.
class GetArrayCase {
    static function main() {
        var a = new hl.NativeArray<Int>(3);
        a[0] = 10;
        a[1] = 20;
        a[2] = 30;
        var sum = 0;
        for (i in 0...a.length) {
            sum += a[i];
        }
        trace(sum);
    }
}
