class MapOps {
    static function main() {
        var m = new Map<String, Int>();
        m.set("a", 1);
        m.set("b", 2);
        m.set("a", 3);
        trace(m.exists("a"));
        m.remove("b");
        trace(m.exists("b"));
        var total = 0;
        for (k in m.keys()) {
            total += m.get(k);
        }
        trace(total);
    }
}
