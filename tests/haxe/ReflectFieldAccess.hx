class ReflectFieldAccessData {
    public var x: Int;
    public var y: Int;
    public function new(x: Int, y: Int) {
        this.x = x;
        this.y = y;
    }
}

class ReflectFieldAccess {
    static function main() {
        var o = new ReflectFieldAccessData(3, 4);
        var v = Reflect.field(o, "x");
        trace(v);
        Reflect.setField(o, "y", 42);
        trace(o.y);
        trace(Reflect.hasField(o, "x"));
        trace(Reflect.hasField(o, "z"));

        var anon = { a: 1, b: "hi" };
        trace(Reflect.field(anon, "b"));
        Reflect.setField(anon, "a", 99);
        trace(anon.a);

        var cls = Type.getClass(o);
        var name = Type.getClassName(cls);
        trace(name);

        var inst = Type.createInstance(ReflectFieldAccessData, [5, 6]);
        trace(inst.x + inst.y);
    }
}
