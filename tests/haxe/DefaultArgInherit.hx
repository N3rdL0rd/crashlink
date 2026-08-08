class Base {
    var x:Int;
    var y:Int;
    public function new(x:Int = 1, y:Int = 2) {
        this.x = x;
        this.y = y;
    }
    public function show():String { return 'x=$x y=$y'; }
}

class Child extends Base {
    var z:Int;
    public function new(x:Int = 1, z:Int = 99) {
        super(x);
        this.z = z;
    }
    override public function show():String { return super.show() + ' z=$z'; }
}

class DefaultArgInherit {
    static function main() {
        var b = new Base();
        Sys.println(b.show());
        var c1 = new Child();
        Sys.println(c1.show());
        var c2 = new Child(5);
        Sys.println(c2.show());
        var c3 = new Child(5, 7);
        Sys.println(c3.show());
    }
}
