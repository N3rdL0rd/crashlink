class VectorAlloc {
    static function main() {
        var v = new haxe.ds.Vector<Int>(4);
        for (i in 0...4) v[i] = i * i;
        var sum = 0;
        for (i in 0...4) sum += v[i];
        Sys.println(sum);
    }
}
