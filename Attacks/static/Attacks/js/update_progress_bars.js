function get_tasks() {
    $.ajax({
        type: 'get',
        url: 'process-attacks/',
        success: function (data) {
            if (data["task_sqli"] != null){
                $('#pgrbar-sqli').text("");
                $('#pgrbar-sqli').val("0");
                $('#pgrbar-sqli').css('width', "0%");
                get_task_info(data["task_sqli"], 'sqli');
            }
            if (data["task_xmli"] != null){
                $('#pgrbar-xmli').text("");
                $('#pgrbar-xmli').val("0");
                $('#pgrbar-xmli').css('width', "0%");
                get_task_info(data["task_xmli"], 'xmli');
            }
            if (data["task_dos"] != null) {
                $('#pgrbar-dos').text("");
                $('#pgrbar-dos').val("0");
                $('#pgrbar-dos').css('width', "0%");
                get_task_info(data["task_dos"], 'dos');
            }
        },
        error: function (data) {
            console.log("Something went wrong !");
        }
    });
    return false;
}

function get_task_info(task_id, attack) {
    $.ajax({
        type: 'get',
        url: 'get-task-info/',
        data: {'task_id': task_id},
        success: function (data) {
            if (data.state === 'PENDING') {
                if (attack === 'sqli') {
                    $('#message-sqli').text('Veuillez patienter...');
                    $('#message-sqli').attr('class', 'text-primary');
                }
                if (attack === 'xmli') {
                    $('#message-xmli').text('Veuillez patienter...');
                    $('#message-xmli').attr('class', 'text-primary');
                }
                if (attack === 'dos') {
                    $('#message-dos').text('Veuillez patienter...');
                    $('#message-dos').attr('class', 'text-primary');
                }
            }
            else if (data.state === 'PROGRESS' || data.state === 'SUCCESS') {
                if (attack === 'sqli') {
                    if (data.result.detection_type === 'static') {
                        $('#message-sqli').attr('class', 'text-primary');
                        $('#message-sqli').text('Détection statique en cours...');
                    }
                    else {
                        $('#message-sqli').attr('class', 'text-primary');
                        $('#message-sqli').text('Détection dynamique en cours ...');
                    }
                    if (data.result.nb_success_attacks === 0) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-sqli-static').attr('class', 'progress-bar bg-success');
                            $('#pgrbar-sqli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-sqli-dynamic').attr('class', 'progress-bar bg-success');
                            $('#pgrbar-sqli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    else if (data.result.nb_success_attacks > 0 && data.result.nb_success_attacks <= 5) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-sqli-static').attr('class', 'progress-bar bg-warning');
                            $('#pgrbar-sqli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-sqli-dynamic').attr('class', 'progress-bar bg-warning');
                            $('#pgrbar-sqli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    else if (data.result.nb_success_attacks > 5) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-sqli-static').attr('class', 'progress-bar bg-danger');
                            $('#pgrbar-sqli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-sqli-dynamic').attr('class', 'progress-bar bg-danger');
                            $('#pgrbar-sqli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    if (data.result.detection_type === 'static') {
                        $('#pgrbar-sqli-static').val(data.result.percent);
                        $('#pgrbar-sqli-static').css('width', data.result.percent.toString().concat("%"));
                    }
                    else {
                        $('#pgrbar-sqli-dynamic').val(data.result.percent);
                        $('#pgrbar-sqli-dynamic').css('width', data.result.percent.toString().concat("%"));
                    }
                }
                if (attack === 'xmli') {
                    if (data.result.detection_type === 'static') {
                        $('#message-xmli').attr('class', 'text-primary');
                        $('#message-xmli').text('Détection statique en cours...');
                    }
                    else {
                        $('#message-xmli').attr('class', 'text-primary');
                        $('#message-xmli').text('Détection dynamique en cours...');
                    }
                    if (data.result.nb_success_attacks === 0) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-xmli-static').attr('class', 'progress-bar bg-success');
                            $('#pgrbar-xmli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-xmli-dynamic').attr('class', 'progress-bar bg-success');
                            $('#pgrbar-xmli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    else if (data.result.nb_success_attacks > 0 && data.result.nb_success_attacks <= 5) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-xmli-static').attr('class', 'progress-bar bg-warning');
                            $('#pgrbar-xmli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-xmli-dynamic').attr('class', 'progress-bar bg-warning');
                            $('#pgrbar-xmli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    else if (data.result.nb_success_attacks > 5) {
                        if (data.result.detection_type === 'static') {
                            $('#pgrbar-xmli-static').attr('class', 'progress-bar bg-danger');
                            $('#pgrbar-xmli-static').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                        else {
                            $('#pgrbar-xmli-dynamic').attr('class', 'progress-bar bg-danger');
                            $('#pgrbar-xmli-dynamic').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_sent_attacks).toString());
                        }
                    }
                    if (data.result.detection_type === 'static') {
                        $('#pgrbar-xmli-static').val(data.result.percent);
                        $('#pgrbar-xmli-static').css('width', data.result.percent.toString().concat("%"));
                    }
                    else {
                        $('#pgrbar-xmli-dynamic').val(data.result.percent);
                        $('#pgrbar-xmli-dynamic').css('width', data.result.percent.toString().concat("%"));
                    }
                }
                if (attack === 'dos') {
                    if ($('#message-dos').text() === '' || $('#message-dos').text() === 'Veuillez patienter...') {
                        $('#message-dos').text('');
                    }
                    if (data.result.nb_success_attacks === 0) {
                        $('#pgrbar-dos').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_valid_requests).toString());
                    }
                    else if (data.result.nb_success_attacks > 0 && data.result.nb_success_attacks <= 5) {
                        $('#pgrbar-dos').attr('class', 'progress-bar bg-warning');
                        $('#pgrbar-dos').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_valid_requests).toString());
                    }
                    else if (data.result.nb_success_attacks > 5) {
                        $('#pgrbar-dos').attr('class', 'progress-bar bg-danger');
                        $('#pgrbar-dos').text(data.result.nb_success_attacks.toString().concat('/').concat(data.result.nb_valid_requests).toString());
                    }
                    $('#pgrbar-dos').val(data.result.percent);
                    $('#pgrbar-dos').css('width', data.result.percent.toString().concat("%"));
                }
            }
            if (data.state === 'SUCCESS') {
                if (attack === 'sqli') {
                    $('#message-sqli').text("Processus de détection terminé avec succès !");
                    $('#message-sqli').attr('class', 'text-success font-weight-bold');
                }
                if (attack === 'xmli') {
                    $('#message-xmli').text('Processus de détection terminé avec succès !');
                    $('#message-xmli').attr('class', 'text-success font-weight-bold');
                }
                if (attack === 'dos') {
                    $('#message-dos').text('Processus de détection terminé avec succès !');
                    $('#message-dos').attr('class', 'text-success font-weight-bold');
                }
                $('#show-report').removeAttr('disabled')
            }
            if (data.state !== 'SUCCESS') {
                setTimeout(function () {
                    get_task_info(task_id, attack)
                }, 1);
            }
        },
        error: function (data) {
            if (attack === 'sqli') {
                $('#message-sqli').text("Une erreur s'est produite !");
                $('#message-sqli').attr('class', 'text-danger');
            }
            if (attack === 'xmli') {
                $('#message-xmli').text('Une erreur s\'est produite !');
                $('#message-xmli').attr('class', 'text-danger');
            }
            if (attack === 'dos') {
                $('#message-dos').text('Une erreur s\'est produite !');
                $('#message-dos').attr('class', 'text-danger');
            }
        }
    });
}