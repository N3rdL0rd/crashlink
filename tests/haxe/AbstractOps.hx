abstract Meter(Float) from Float to Float {
    @:op(A + B)
    function add(other:Meter):Meter {
        return this + (other : Float);
    }
}

class AbstractOps {
    static function main() {
        var a:Meter = 1.5;
        var b:Meter = 2.25;
        var total:Float = a + b;
        Sys.println(total);
    }
}
