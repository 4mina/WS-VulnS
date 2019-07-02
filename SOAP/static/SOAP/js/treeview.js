$(function () {
    // Create an instance when the DOM is ready
    $('#wsdl-explorer-tree').jstree();
    // Bind to events triggered on the tree
    $('#wsdl-explorer-tree').on("changed.jstree", function (e, data) {
        console.log(data.selected);
        var node = data.instance.get_node(data.selected);
        var data_type = $("#" + node.id).attr('data-type');

        if (data_type === "soap-web-service")
        {
            if (node.id.length > 0)
            {
                var web_service_id = node.id.replace("web-service-", "");
                console.log(web_service_id);
                $.ajax({
                    url: "web_service_info/".concat(web_service_id).concat("/"),
                    data: web_service_id,
                    success: function(data) {
                        $("#wsdl-info").html(data);
                    }
                });
            }

        }
        else if (data_type === "soap-endpoint")
        {
            if (node.id.length > 0)
            {
                var endpoint_id = node.id.replace("endpoint-", "");
                console.log(endpoint_id);
                $.ajax({
                    url: "endpoint_info/".concat(endpoint_id).concat("/"),
                    data: endpoint_id,
                    success: function(data) {
                        $("#wsdl-info").html(data);
                    }
                });
            }

        }
        else if (data_type === "soap-operation")
        {
            if (node.id.length > 0)
            {
                var operation_id = node.id.replace("operation-", "");
                console.log(operation_id);
                $.ajax({
                    url: "operation_info/".concat(operation_id).concat("/"),
                    data: operation_id,
                    success: function(data) {
                        $("#wsdl-info").html(data);
                    }
                });
            }

        }

    });
});
