class Mat {
    public var a:Float = 1.0;
    public var b:Float = 2.0;
    public var c:Float = 3.0;
    public var d:Float = 4.0;
    public var x:Float = 5.0;
    public var y:Float = 6.0;

    public function new() {}
}

class NamedRegisterTemps {
    public var x:Float;
    public var y:Float;

    public function new(x:Float, y:Float) {
        this.x = x;
        this.y = y;
    }

    // Same shape as h2d.col.PointImpl.transform.
    public function transform(m:Mat):Void {
        var mx = m.a * x + m.c * y + m.x;
        var my = m.b * x + m.d * y + m.y;
        x = mx;
        y = my;
    }

    static function main() {
        var p = new NamedRegisterTemps(1.5, 2.5);
        p.transform(new Mat());
        Sys.println(p.x + "," + p.y);
    }
}
