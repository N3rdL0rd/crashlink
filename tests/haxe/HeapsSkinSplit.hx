class Joint {
    public var splitIndex:Int = -1;
    public var bindIndex:Int;
    public function new(bindIndex:Int) {
        this.bindIndex = bindIndex;
    }
}

class Permut {
    public var joints:Array<Joint>;
    public var triangles:Array<Int>;
    public var material:Int;
    public function new() {}
}

class HeapsSkinSplit {
    var boundJoints:Array<Joint>;
    var vertexWeights:Array<Float>;
    var vertexJoints:Array<Int>;
    var bonesPerVertex:Int;
    var splitJoints:Array<Joint>;
    var triangleGroups:haxe.ds.Vector<Int>;

    function new(boundJoints:Array<Joint>, vertexWeights:Array<Float>, vertexJoints:Array<Int>, bonesPerVertex:Int) {
        this.boundJoints = boundJoints;
        this.vertexWeights = vertexWeights;
        this.vertexJoints = vertexJoints;
        this.bonesPerVertex = bonesPerVertex;
    }

    public inline function isSplit() {
        return splitJoints != null;
    }

    function sortByBindIndex(j1: Joint, j2: Joint) {
        return j1.bindIndex - j2.bindIndex;
    }

    function isSub(a: Array<Joint>, b: Array<Joint>) {
        var j = 0;
        var max = b.length;
        for (e in a) {
            while (e != b[j++]) {
                if (j >= max) return false;
                continue;
            }
        }
        return true;
    }

    function merge(permuts: Array<Permut>) {
        for (p1 in permuts)
            for (p2 in permuts)
                if (p1 != p2 && p1.material == p2.material && isSub(p1.joints, p2.joints)) {
                    for (t in p1.triangles)
                        p2.triangles.push(t);
                    permuts.remove(p1);
                    return true;
                }
        return false;
    }

    function jointsDiff(p1: Permut, p2: Permut) {
        var diff = 0;
        var i = 0, j = 0;
        var imax = p1.joints.length, jmax = p2.joints.length;
        while (i < imax && j < jmax) {
            var j1 = p1.joints[i];
            var j2 = p2.joints[j];
            if (j1 == j2) {
                i++;
                j++;
            } else {
                diff++;
                if (j1.bindIndex < j2.bindIndex)
                    i++;
                else
                    j++;
            }
        }
        return diff + (imax - i) + (jmax - j);
    }

    public function split(maxBones:Int, index:Array<Int>, triangleMaterials:Null<Array<Int>>) {
        if (isSplit())
            return true;
        if (boundJoints.length <= maxBones)
            return false;

        splitJoints = [];
        triangleGroups = new haxe.ds.Vector(Std.int(index.length / 3));

        var permuts = new Array<Permut>();

        for (tri in 0...Std.int(index.length / 3)) {
            var iid = tri * 3;
            var mid = triangleMaterials == null ? 0 : triangleMaterials[tri];
            var jl = [];
            for (i in 0...3) {
                var vid = index[iid + i];
                for (b in 0...bonesPerVertex) {
                    var bidx = vid * bonesPerVertex + b;
                    if (vertexWeights[bidx] == 0) continue;
                    var j = boundJoints[vertexJoints[bidx]];
                    if (j.splitIndex != iid) {
                        j.splitIndex = iid;
                        jl.push(j);
                    }
                }
            }
            jl.sort(sortByBindIndex);
            for (p2 in permuts)
                if (p2.material == mid && isSub(jl, p2.joints)) {
                    p2.triangles.push(tri);
                    jl = null;
                    break;
                }
            if (jl == null) continue;

            for (p2 in permuts)
                if (p2.material == mid && isSub(p2.joints, jl)) {
                    p2.joints = jl;
                    p2.triangles.push(tri);
                    jl = null;
                    break;
                }

            if (jl == null) continue;

            var pr = new Permut();
            pr.joints = jl;
            pr.triangles = [tri];
            pr.material = mid;
            permuts.push(pr);
        }

        while (true) {
            while (merge(permuts)) {}

            var minDif = 100000, minTot = 100000, minP1:Permut = null, minP2:Permut = null;
            for (i in 0...permuts.length) {
                var p1 = permuts[i];
                if (p1.joints.length == maxBones) continue;
                for (j in i + 1...permuts.length) {
                    var p2 = permuts[j];
                    if (p2.joints.length == maxBones || p1.material != p2.material) continue;
                    var count = jointsDiff(p1, p2);
                    var tot = count + ((p1.joints.length + p2.joints.length - count) >> 1);
                    if (tot > maxBones || tot > minTot || (tot == minTot && count > minDif)) continue;
                    minDif = count;
                    minTot = tot;
                    minP1 = p1;
                    minP2 = p2;
                }
            }

            if (minP1 == null) break;

            var p1 = minP1, p2 = minP2;
            for (j in p1.joints) {
                p2.joints.remove(j);
                p2.joints.push(j);
            }
            p2.joints.sort(sortByBindIndex);
            for (t in p1.triangles)
                p2.triangles.push(t);
            permuts.remove(p1);
        }

        for (i in 0...permuts.length)
            for (tri in permuts[i].triangles)
                triangleGroups[tri] = i;

        return true;
    }

    static function main() {
        var joints = [new Joint(0), new Joint(1), new Joint(2), new Joint(3), new Joint(4)];
        var index = [0, 1, 2, 1, 2, 3, 2, 3, 4, 0, 2, 4];
        var vertexJoints = [0, 1, 2, 3, 4];
        var vertexWeights = [1.0, 1.0, 1.0, 1.0, 1.0];
        var s = new HeapsSkinSplit(joints, vertexWeights, vertexJoints, 1);
        trace(s.split(2, index, [0, 1, 0, 1]));
    }
}
