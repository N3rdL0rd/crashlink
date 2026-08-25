class StaticClosureArrayIndexAssign {
    public static var handlers:Array<Int->Int> = [null, null];

    public static function register():Void {
        handlers[0] = function(x:Int):Int return x + 1;
        handlers[1] = function(x:Int):Int return x * 2;
    }

    public static function main():Void {
        register();
        trace(handlers[0](5));
        trace(handlers[1](5));
    }
}
