class QualityConstants {
    @:keep @:noInline public static function value(input:Int):Int {
        return input + 17;
    }

    public static function main():Void {
        Sys.println(value(-3));
        Sys.println(value(0));
        Sys.println(value(25));
    }
}
