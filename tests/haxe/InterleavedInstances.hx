class InterleavedInstances {
    var name:String;
    var count:Int;
    public function new(name:String) { this.name = name; count = 0; }
    public function bump():Int { count++; return count; }
    public function label():String { return name + ":" + count; }

    static function main() {
        var a = new InterleavedInstances("a");
        var b = new InterleavedInstances("b");
        a.bump();
        b.bump();
        b.bump();
        a.bump();
        Sys.println(a.label());
        Sys.println(b.label());
        a.bump();
        Sys.println(a.label());
        Sys.println(b.label());
    }
}
