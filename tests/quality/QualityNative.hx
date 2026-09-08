class QualityNative {
    public var value:Int;

    public function new(value:Int) {
        this.value = value;
    }

    @:keep @:noInline public static function add(left:Int, right:Int):Int {
        return left + right;
    }

    @:keep @:noInline public function bump(delta:Int):Int {
        value = add(value, delta);
        return value;
    }

    public static function main():Void {
        var instance = new QualityNative(17);
        Sys.println(instance.bump(5));
        Sys.println(add(-4, 9));
    }
}
