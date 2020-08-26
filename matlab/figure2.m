markers = ["-o","-x","-s","-d","-+","-p"];

% Load data
simulation_data_figure2

% Create figures folder
if ~exist('../figures', 'dir')
   mkdir('../figures')
end


% First figure - Malicious devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southeast');

for i = 1:length(devices_per_cluster)
    errorbar(malicious_devices_prop, malicious_quarantined(i,:), malicious_quarantined_errorbars(i,:), markers(i),'MarkerSize',7, 'LineWidth',1,'DisplayName',sprintf('%i devices/flow', devices_per_cluster(i)))
end

xlabel('Probability of a device to be malicious')
ylabel('Malicious devices quarantined')
saveas(gcf,'../figures/figure_2_1','png')
print -depsc -r600 ../figures/figure_2_1.eps


% Second figure - Legitimate devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southeast');

for i = 1:length(devices_per_cluster)
    errorbar(malicious_devices_prop, legitimate_quarantined(i,:), legitimate_quarantined_errorbars(i,:), markers(i),'MarkerSize',7,'LineWidth',1,'DisplayName',sprintf('%i devices/flow', devices_per_cluster(i)))
end

xlabel('Probability of a device to be malicious')
ylabel('Legitimate devices quarantined')
saveas(gcf,'../figures/figure_2_2','png')
print -depsc -r600 ../figures/figure_2_2.eps