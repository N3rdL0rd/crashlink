class StaticArrayIndexAssignInt {
    public static var nums:Array<Int> = [0, 0, 0];

    public static function fill():Void {
        nums[0] = 10;
        nums[1] = 20;
        nums[2] = 30;
    }

    public static function main():Void {
        fill();
        trace(nums[0]);
        trace(nums[1]);
        trace(nums[2]);
    }
}
