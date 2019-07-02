$(function treeView() {
    // Create an instance when the DOM is ready
    $('#swagger-explorer-tree').jstree();
    // Bind to events triggered on the tree
    $('#swagger-explorer-tree').on("changed.jstree", function (e, data) {
        var node = data.instance.get_node(data.selected);
        var data_type = $("#" + node.id).attr('data-type');

        if (data_type === "rest-web-service")
        {
            var web_service_id = node.id.replace("ws-", "");
            $.ajax({
                url: "rest_web_service/",
                data: web_service_id,
                success: function(data) {
                    $("#swagger-info").html(data);
                }
            });

        }
        else if (data_type === "path")
        {
            var path_id = node.id.replace("path-", "");
            $.ajax({
                url: "path/".concat(path_id).concat("/"),
                data: path_id,
                success: function(data) {
                    $("#swagger-info").html(data);
                }
            });

        }
        else if (data_type === "method")
        {
            var method_id = node.id.replace("method-", "");
            $.ajax({
                url: "method/".concat(method_id).concat("/"),
                data: method_id,
                success: function(data) {
                    $("#swagger-info").html(data);
                }
            });
        }
    });
});